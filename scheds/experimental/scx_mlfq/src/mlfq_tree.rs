// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the GNU
// General Public License version 2.

//! CART regression tree for next-CPU-burst prediction.
//!
//! The tree predicts the next burst in nsecs from per-task features and
//! the prediction maps to a queue band (pred < T_INT -> Q1, pred <
//! T_BOUND -> Q2, else Q3). It is trained offline in the daemon on
//! samples emitted by the BPF side and published into a double-buffered
//! two-entry array map in `src/bpf/intf.h`, which the classification
//! path walks.
//!
//! The node format, the BFS level-order serialization and the prediction
//! walk are shared with the BPF side: [`TreeNode`] is the byte-for-byte
//! mirror of `struct mlfq_tree_node` (24 bytes under `#[repr(C)]`), and
//! [`predict`] implements the same masked, depth-capped descent as
//! `mlfq_tree_walk()` in `src/bpf/intf.h`. `serialize_validate()`
//! checks a tree against the invariants the walk relies on; the daemon
//! must not commit a tree that fails it.
//!
//! Growth is classic CART variance reduction: each split minimizes the
//! sum of squared errors of the two child groups, thresholds are exact
//! u64 nsec midpoints between distinct feature values, and growth stops
//! at `max_depth`, `min_samples_leaf`, `max_nodes` or a minimum relative
//! variance reduction.

use std::collections::VecDeque;

/// Node budget of the shared store entry, from `src/bpf/intf.h`. A power
/// of two, so the walk's index mask is `MAX_NODES - 1`.
const MLFQ_TREE_MAX_NODES: usize = crate::bpf_intf::mlfq_consts_MLFQ_TREE_MAX_NODES as usize;

/// Walk depth bound of the shared store entry, from `src/bpf/intf.h`.
const MLFQ_TREE_MAX_DEPTH: usize = crate::bpf_intf::mlfq_consts_MLFQ_TREE_MAX_DEPTH as usize;

/// Number of populated features; ids 0..8 index the walk's `feat[9]` slots,
/// sleep_var_ratio at id 9 is carry-along for the next ABI, gpu_submit at 8 quantised 0..4.
const MLFQ_TREE_NR_FEATURES: usize = 9;

/// Default minimum relative variance reduction for a split.
///
/// A split must remove at least 0.1% of the node's label variance to be
/// taken. At the daemon's training-set size (2048 samples) a random split
/// on a noise feature removes about 1/sqrt(n) ~= 2% of the variance at
/// best by chance, so the gate is below that; it prunes the splits that
/// only chase sample noise while keeping every split that materially
/// separates the queue bands. The choice is a relative threshold, so it
/// scales with the label magnitude and needs no unit-dependent tuning.
pub const DEFAULT_MIN_REL_VAR_REDUCTION: f64 = 1e-3;

/// Scratch buffers for the CART fit, sized to the maximum window and node
/// budget. The buffers are allocated once with the capacities below and
/// reused across fits by clearing in place, so the training path does not
/// allocate after the first fit. The queue holds owned sample vectors per
/// node; those vectors are still allocated per node, but the major buffers
/// (weights, sorted, left/right) are reused. This keeps the 60s training
/// free of steady-state allocations while preserving the exact CART logic.
pub struct FitScratch {
    pub weights: Vec<f64>,
    pub sorted: Vec<WeightedSample>,
    pub left: Vec<WeightedSample>,
    pub right: Vec<WeightedSample>,
    pub nodes: Vec<TreeNode>,
    #[allow(private_interfaces)]
    pub queue: VecDeque<NodeSpec>,
    pub preds: Vec<u64>,
    pub actuals: Vec<u64>,
    pub ema_preds: Vec<u64>,
    pub weights_full: Vec<f64>,
}

impl FitScratch {
    /// Create a scratch arena with capacities for the maximum window.
    pub fn new() -> Self {
        Self {
            weights: Vec::with_capacity(16384),
            sorted: Vec::with_capacity(16384),
            left: Vec::with_capacity(16384),
            right: Vec::with_capacity(16384),
            nodes: Vec::with_capacity(2048),
            queue: VecDeque::with_capacity(2048),
            preds: Vec::with_capacity(2048),
            actuals: Vec::with_capacity(2048),
            ema_preds: Vec::with_capacity(2048),
            weights_full: Vec::with_capacity(16384),
        }
    }
}

impl Default for FitScratch {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-task feature vector, the mirror of `struct mlfq_tree_feats`.
///
/// Field order is part of the shared ABI with the BPF sample struct and
/// the emitted `mlfq_tree_sample` layout. `prev_burst_ns`, `sleep_ns`,
/// `ema`, `io_wait`, `wake_cnt`, then the measured service fields
/// (`wake_lat_us`, `queue_wait_us`, `sq_ema`), the cadence feature
/// (`sleep_var_ratio`) and the gpu feature (`gpu_submit` quant 0..4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct TreeFeats {
    /// Last completed run segment, in nsecs.
    pub prev_burst_ns: u64,
    /// Sleep before the current wakeup, in nsecs.
    pub sleep_ns: u64,
    /// EMA interactivity gauge.
    pub ema: u64,
    /// 1 if the wakeup is an I/O completion.
    pub io_wait: u32,
    /// Consecutive short-sleep wakeups.
    pub wake_cnt: u32,
    /// Last wakeup-to-run latency of the task, in microseconds.
    pub wake_lat_us: u32,
    /// Last enqueue-to-run wait of the task, in microseconds.
    pub queue_wait_us: u32,
    /// Per-task service-quality EMA (nsecs), saturating.
    pub sq_ema: u64,
    /// Sleep variation ratio, FP_SHIFT fixed point (8).
    pub sleep_var_ratio: u32,
    /// Pad to 64-byte alignment.
    pub pad: u32,
    /// GPU submissions quantised 0..4.
    pub gpu_submit: u32,
    /// Pad to 64 bytes, keeps 8-byte tail alignment.
    pub pad2: u32,
}

/// One training sample, the mirror of `struct mlfq_tree_sample`.
///
/// `label_ns` is the run segment that followed the feature capture; the
/// tree regresses it against `feats`. `version` carries
/// `MLFQ_TREE_SAMPLE_VERSION` and is checked by the daemon's parse, so
/// a record from an out-of-tree producer fails the check instead of
/// being misread. The BPF struct is `packed, aligned(4)` to keep the
/// record at 84 bytes, so this mirror is packed identically; every
/// field sits at its naturally aligned offset, and the daemon reads the
/// record with `read_unaligned`.
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct TreeSample {
    /// Emitting task.
    pub pid: u32,
    /// Queue the task was placed in at capture.
    pub queue: u32,
    /// Feature vector at capture.
    pub feats: TreeFeats,
    /// Run segment that followed, in nsecs (the label).
    pub label_ns: u64,
    /// Sample-record layout version (`MLFQ_TREE_SAMPLE_VERSION`).
    pub version: u32,
}

/// One tree node, the byte-for-byte mirror of `struct mlfq_tree_node`.
///
/// For an internal node (`right != 0`), `threshold` is the split point in
/// nsecs, `left`/`right` the child indices and `feature` the split feature
/// id (0..7). For a leaf (`right == 0`), `left` carries the prediction in
/// nsecs. `pad` is the 7 reserved bytes of the 24-byte node; it is always
/// zeroed so the published node bytes are deterministic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct TreeNode {
    /// Split point in nsecs (internal nodes); 0 on leaves.
    pub threshold: u64,
    /// Left child index, or the leaf prediction when `right == 0`.
    pub left: u32,
    /// Right child index; 0 marks a leaf.
    pub right: u32,
    /// Split feature id (0..7); 0 on leaves.
    pub feature: u8,
    /// Reserved padding, always zeroed.
    pub pad: [u8; 7],
}

/// A fitted tree in the shared serialized form: BFS level order, index 0
/// = root, parents before children. The daemon writes these nodes at the
/// front of a map entry's node buffer (the entry and its tail are
/// zeroed, which is the untrained shape); `serialize_validate()` must
/// pass before the daemon commits the tree.
#[derive(Clone, Debug, Default)]
pub struct SerializedTree {
    /// Live nodes in BFS level order; index 0 is the root.
    pub nodes: Vec<TreeNode>,
}

/// Feature value for a feature id, matching the BPF walk's `feat[9]` slot
/// layout in `src/bpf/intf.h` (`mlfq_tree_walk`). Ids 0..8 are the split
/// features (prev_burst, sleep, ema, io_wait, wake_cnt, wake_lat,
/// queue_wait, sq_ema, gpu_submit), id 9 the cadence ratio (carry-along,
/// split when NR_FEATURES promotes it), and the rest zero.
fn feat_value(f: TreeFeats, id: u8) -> u64 {
    match id {
        0 => f.prev_burst_ns,
        1 => f.sleep_ns,
        2 => f.ema,
        3 => f.io_wait as u64,
        4 => f.wake_cnt as u64,
        5 => f.wake_lat_us as u64,
        6 => f.queue_wait_us as u64,
        7 => f.sq_ema,
        8 => f.gpu_submit as u64,
        9 => f.sleep_var_ratio as u64,
        _ => 0,
    }
}

/// Overflow-safe midpoint between two distinct u64 values.
///
/// `v + (w - v) / 2` never wraps: `w - v` is exact for `w > v`, and the
/// halved difference is at most `w - v`, so the sum is at most `w`.
/// Consecutive values collapse to the lower one, which still separates
/// them (the lower value routes left, the higher routes right).
fn midpoint(v: u64, w: u64) -> u64 {
    debug_assert!(w > v);
    v + (w - v) / 2
}

/// A training sample paired with its recency weight, the unit the fit
/// carries through the node partitions.
type WeightedSample = (TreeSample, f64);

/// One node in the BFS queue during fit. The samples are the weighted
/// samples that reached this node. This is an internal detail of the
/// fit and is not part of the published tree.
pub(crate) struct NodeSpec {
    idx: usize,
    samples: Vec<WeightedSample>,
    depth: usize,
}

/// Recency weight of each training sample, by its age in the window.
///
/// age_i = n - i (i = 0 is the oldest sample, n the window length) and
/// the half-life is half the window: w_i = 2^(-age_i / (n / 2)). The
/// newest sample weighs ~1 and the oldest exactly 2^-2 = 0.25, so the
/// fit concentrates on the recent regime without dropping the older
/// data entirely and no weight can underflow. Each weight is one
/// `powf`, so there is no error accumulation across samples.
#[allow(dead_code)]
pub fn sample_weights(n: usize) -> Vec<f64> {
    let half_life = n as f64 / 2.0;
    (0..n)
        .map(|i| 2.0f64.powf(-((n - i) as f64) / half_life))
        .collect()
}

/// Fill the provided buffer with recency weights without allocating.
/// The buffer is cleared and filled to length n; capacity is retained
/// so the second call with the same n does not allocate.
pub fn sample_weights_into(n: usize, out: &mut Vec<f64>) {
    out.clear();
    if out.capacity() < n {
        out.reserve(n - out.len());
    }
    let half_life = n as f64 / 2.0;
    for i in 0..n {
        out.push(2.0f64.powf(-((n - i) as f64) / half_life));
    }
}

/// Sum of weights, weighted sum and weighted sum-of-squares of a node's
/// labels, in f64 for the variance math. Each sample carries its
/// recency weight alongside it.
fn label_totals(samples: &[WeightedSample]) -> (f64, f64, f64) {
    samples
        .iter()
        .fold((0.0, 0.0, 0.0), |(sw, swy, swy2), (s, w)| {
            let y = s.label_ns as f64;
            (sw + w, swy + w * y, swy2 + w * y * y)
        })
}

/// Partition a node's samples by a split, mirroring the walk's `<=`
/// routing. `feat_value <= threshold` goes left. The recency weights
/// ride along with their samples.
#[allow(dead_code)]
fn partition(
    samples: &[WeightedSample],
    feature: u8,
    threshold: u64,
) -> (Vec<WeightedSample>, Vec<WeightedSample>) {
    let mut left = Vec::with_capacity(samples.len());
    let mut right = Vec::with_capacity(samples.len());
    for s in samples {
        if feat_value(s.0.feats, feature) <= threshold {
            left.push(*s);
        } else {
            right.push(*s);
        }
    }
    (left, right)
}

/// Clamp a leaf mean to the u32 prediction field of the shared node.
///
/// A mean beyond 2^32 - 1 nsecs (about 4.3 s) is beyond the scheduler's
/// timescale (the Q3 slice is 4 ms), so it saturates; the walk returns
/// the field as-is.
fn leaf_prediction(mean_ns: u64) -> u32 {
    mean_ns.min(u32::MAX as u64) as u32
}

/// Search the best binary split for a node's samples.
///
/// For each feature, the samples are sorted by the feature value and the
/// midpoints between distinct values are swept in order. The left group
/// accumulates the weighted label sum and sum-of-squares so the weighted
/// SSE of both groups is O(1) per candidate. Both groups must meet
/// `min_samples_leaf` (a sample count, unchanged by the recency
/// weighting) and the split must remove at least
/// `min_rel_var_reduction * sse`. The first maximum-reduction split
/// wins, so ties resolve to the smallest threshold that reaches the
/// reduction.
///
/// Returns `(feature, threshold)`.
#[allow(dead_code)]
fn best_split(
    samples: &[WeightedSample],
    min_samples_leaf: usize,
    sse: f64,
    min_rel_var_reduction: f64,
) -> Option<(u8, u64)> {
    let n = samples.len();
    let (total_w, total_wy, total_wy2) = label_totals(samples);
    let min_reduction = sse * min_rel_var_reduction;
    let mut best: Option<(u8, u64, f64)> = None;

    for feature in 0..MLFQ_TREE_NR_FEATURES {
        let mut sorted: Vec<WeightedSample> = samples.to_vec();
        sorted.sort_by_key(|(s, _)| feat_value(s.feats, feature as u8));

        let mut sw_l = 0.0f64;
        let mut swy_l = 0.0f64;
        let mut swy2_l = 0.0f64;
        let mut i = 0usize;
        while i < n {
            let v = feat_value(sorted[i].0.feats, feature as u8);
            let mut j = i;
            while j < n && feat_value(sorted[j].0.feats, feature as u8) == v {
                let (s, w) = sorted[j];
                let y = s.label_ns as f64;
                sw_l += w;
                swy_l += w * y;
                swy2_l += w * y * y;
                j += 1;
            }

            /* Left group = all values <= v. A split needs a higher value. */
            let n_l = j;
            let n_r = n - j;
            if n_l >= min_samples_leaf && n_r >= min_samples_leaf && j < n {
                let v_next = feat_value(sorted[j].0.feats, feature as u8);
                let threshold = midpoint(v, v_next);
                let sse_l = swy2_l - swy_l * swy_l / sw_l;
                let sw_r = total_w - sw_l;
                let swy_r = total_wy - swy_l;
                let swy2_r = total_wy2 - swy2_l;
                let sse_r = swy2_r - swy_r * swy_r / sw_r;
                let reduction = sse - sse_l - sse_r;

                if reduction > min_reduction {
                    let replace = match best {
                        Some((_, _, r)) => reduction > r,
                        None => true,
                    };
                    if replace {
                        best = Some((feature as u8, threshold, reduction));
                    }
                }
            }
            i = j;
        }
    }

    best.map(|(f, t, _)| (f, t))
}

/// Variant of best_split that reuses a caller-provided buffer for sorting.
/// The buffer is cleared and filled from samples for each feature, so the
/// per-feature allocation is avoided after the first call.
fn best_split_with_scratch(
    samples: &[WeightedSample],
    min_samples_leaf: usize,
    sse: f64,
    min_rel_var_reduction: f64,
    scratch: &mut Vec<WeightedSample>,
) -> Option<(u8, u64)> {
    let n = samples.len();
    let (total_w, total_wy, total_wy2) = label_totals(samples);
    let min_reduction = sse * min_rel_var_reduction;
    let mut best: Option<(u8, u64, f64)> = None;

    for feature in 0..MLFQ_TREE_NR_FEATURES {
        scratch.clear();
        scratch.extend_from_slice(samples);
        scratch.sort_by_key(|(s, _)| feat_value(s.feats, feature as u8));
        let sorted = &*scratch;

        let mut sw_l = 0.0f64;
        let mut swy_l = 0.0f64;
        let mut swy2_l = 0.0f64;
        let mut i = 0usize;
        while i < n {
            let v = feat_value(sorted[i].0.feats, feature as u8);
            let mut j = i;
            while j < n && feat_value(sorted[j].0.feats, feature as u8) == v {
                let (s, w) = sorted[j];
                let y = s.label_ns as f64;
                sw_l += w;
                swy_l += w * y;
                swy2_l += w * y * y;
                j += 1;
            }

            /* Left group = all values <= v. A split needs a higher value. */
            let n_l = j;
            let n_r = n - j;
            if n_l >= min_samples_leaf && n_r >= min_samples_leaf && j < n {
                let v_next = feat_value(sorted[j].0.feats, feature as u8);
                let threshold = midpoint(v, v_next);
                let sse_l = swy2_l - swy_l * swy_l / sw_l;
                let sw_r = total_w - sw_l;
                let swy_r = total_wy - swy_l;
                let swy2_r = total_wy2 - swy2_l;
                let sse_r = swy2_r - swy_r * swy_r / sw_r;
                let reduction = sse - sse_l - sse_r;

                if reduction > min_reduction {
                    let replace = match best {
                        Some((_, _, r)) => reduction > r,
                        None => true,
                    };
                    if replace {
                        best = Some((feature as u8, threshold, reduction));
                    }
                }
            }
            i = j;
        }
    }

    best.map(|(f, t, _)| (f, t))
}

/// Grow a CART regression tree over `samples`.
///
/// The growth is breadth-first so the serialized node order is the
/// level-order layout the store requires (parents before children, index
/// 0 = root). Each node is created as a placeholder, queued, and filled
/// when processed. A node that clears the growth limits becomes an
/// internal node (two new children) and everything else becomes a leaf
/// predicting the weighted mean of its labels.
///
/// Growth stops at `max_depth` edges, when either child would fall below
/// `min_samples_leaf`, when the node budget `max_nodes` would be exceeded
/// (every node in the tree, internal or leaf, counts), or when no split
/// removes `min_rel_var_reduction` of the node's label variance.
///
/// Every training sample is weighted by its recency in the window
/// (`sample_weights`: 2^(-age/(n/2))), so the fit concentrates on the
/// recent regime while the full window still provides the data quantity
/// and the gates bound every publish. The weighting enters the fit as a
/// weighted SSE. The leaf means and the variance-reduction ranking are
/// weighted, and the `min_samples_leaf` cap still counts samples, not
/// weight.
///
/// All arithmetic is f64 on the weighted label sums. The labels are
/// emitted by the BPF side clamped to `MLFQ_TREE_LABEL_MAX_NS` (see
/// `src/bpf/intf.h`), so the exact-integer range the SSE math sums is
/// bounded: a label value of at most 192 ms squares to ~3.7e16, far
/// below the f64 rounding error. The weights live in [0.25, 1], so the
/// weighted sums stay within the same magnitude as the uniform fit and
/// the split ranking is exact except for near-tied candidates containing
/// extreme labels, where consecutive u64 values collapse in the f64
/// conversion and the tie-break is approximate; the daemon never sees
/// such labels because of the emission clamp.
///
/// An empty `samples` slice or `max_nodes == 0` yields an empty tree,
/// which `serialize_validate()` rejects; the daemon treats an empty tree
/// as untrained.
#[allow(dead_code)]
pub fn fit(
    samples: &[TreeSample],
    max_depth: usize,
    min_samples_leaf: usize,
    max_nodes: usize,
    min_rel_var_reduction: f64,
) -> SerializedTree {
    let mut scratch = FitScratch::new();
    fit_with_scratch(
        samples,
        max_depth,
        min_samples_leaf,
        max_nodes,
        min_rel_var_reduction,
        &mut scratch,
    )
}

/// Fit a tree reusing the caller-provided scratch arena. After the first
/// call the arena retains its capacity, so subsequent fits do not allocate.
/// The logic is identical to `fit()`, only the temporary buffers are reused.
pub fn fit_with_scratch(
    samples: &[TreeSample],
    max_depth: usize,
    min_samples_leaf: usize,
    max_nodes: usize,
    min_rel_var_reduction: f64,
    scratch: &mut FitScratch,
) -> SerializedTree {
    if samples.is_empty() || max_nodes == 0 {
        return SerializedTree::default();
    }

    sample_weights_into(samples.len(), &mut scratch.weights);
    let weights = &scratch.weights;
    scratch.nodes.clear();
    scratch.nodes.reserve(max_nodes);
    scratch.queue.clear();
    // Node storage is in the scratch arena. Clear but keep capacity.
    let nodes = &mut scratch.nodes;
    let queue = &mut scratch.queue;
    nodes.push(TreeNode::default()); /* root placeholder */
    // Build the weighted samples for the root. Reuse the left buffer as
    // temporary weighted storage, then move it into the root.
    scratch.left.clear();
    for (s, w) in samples.iter().copied().zip(weights.iter().copied()) {
        scratch.left.push((s, w));
    }
    let mut root_samples = Vec::new();
    std::mem::swap(&mut root_samples, &mut scratch.left);
    queue.push_back(NodeSpec {
        idx: 0,
        samples: root_samples,
        depth: 0,
    });

    while let Some(spec) = queue.pop_front() {
        let n = spec.samples.len();
        let (sw, swy, swy2) = label_totals(&spec.samples);
        let sse = swy2 - swy * swy / sw;

        let splittable = spec.depth < max_depth
            && n >= 2 * min_samples_leaf
            && nodes.len() + 2 <= max_nodes
            /*
             * The SSE of a node with (near-)constant labels is dominated
             * by floating-point cancellation noise, which is bounded by
             * ~1e-13 of the squared-label magnitude. A node whose SSE
             * sits below 1e-12 of its weighted sum-of-squares is treated
             * as a leaf, so the splitter never chases rounding noise
             * (a random split on a noise feature can only "reduce" that
             * noise, and min_rel_var_reduction is far above this floor).
             */
            && sse > 1e-12 * swy2;
        let best = if splittable {
            // Reuse the sorted buffer from the scratch arena.
            best_split_with_scratch(
                &spec.samples,
                min_samples_leaf,
                sse,
                min_rel_var_reduction,
                &mut scratch.sorted,
            )
        } else {
            None
        };

        match best {
            Some((feature, threshold)) => {
                let left_idx = nodes.len() as u32;
                let right_idx = left_idx + 1;
                nodes[spec.idx] = TreeNode {
                    threshold,
                    left: left_idx,
                    right: right_idx,
                    feature,
                    pad: [0; 7],
                };
                /* Child placeholders, filled when dequeued. */
                nodes.push(TreeNode::default());
                nodes.push(TreeNode::default());
                // Reuse the left/right buffers from the scratch arena.
                // partition_into clears and fills them, then we move the
                // filled vectors into the queue. The scratch buffers are
                // left empty but retain capacity for the next split.
                scratch.left.clear();
                scratch.right.clear();
                for s in &spec.samples {
                    if feat_value(s.0.feats, feature) <= threshold {
                        scratch.left.push(*s);
                    } else {
                        scratch.right.push(*s);
                    }
                }
                let mut left = Vec::new();
                let mut right = Vec::new();
                std::mem::swap(&mut left, &mut scratch.left);
                std::mem::swap(&mut right, &mut scratch.right);
                queue.push_back(NodeSpec {
                    idx: left_idx as usize,
                    samples: left,
                    depth: spec.depth + 1,
                });
                queue.push_back(NodeSpec {
                    idx: right_idx as usize,
                    samples: right,
                    depth: spec.depth + 1,
                });
            }
            None => {
                nodes[spec.idx] = TreeNode {
                    threshold: 0,
                    left: leaf_prediction((swy / sw) as u64),
                    right: 0,
                    feature: 0,
                    pad: [0; 7],
                };
            }
        }
    }

    let mut out_nodes = Vec::new();
    std::mem::swap(&mut out_nodes, nodes);
    SerializedTree { nodes: out_nodes }
}

/// Validate a tree against the walk's invariants before publishing.
///
/// Every node count must sit in `[1, MLFQ_TREE_MAX_NODES]`. Every node
/// must be reachable from the root. Every leaf (`right == 0`) is
/// unconstrained beyond that. Every internal node must split on a feature
/// id below the nine populated slots, both children must be in-bounds,
/// and both must follow the parent in the BFS order (parents before
/// children), which the store layout relies on.
///
/// The walk descends at most `MLFQ_TREE_MAX_DEPTH` edges and then, depth
/// exhausted, returns the last reachable node's `left` only when that
/// node is a leaf. A node deeper than `MLFQ_TREE_MAX_DEPTH` is therefore
/// unreachable, and an internal node at depth `MLFQ_TREE_MAX_DEPTH`
/// would only ever be read through the exhaustion fallback (predicting
/// 0). Both shapes are rejected, so a published tree's every reachable
/// prediction is a real leaf.
pub fn serialize_validate(tree: &SerializedTree) -> Result<(), String> {
    let nr = tree.nodes.len();
    if nr < 1 {
        return Err("empty tree: the root node is required".into());
    }
    if nr > MLFQ_TREE_MAX_NODES {
        return Err(format!(
            "{nr} nodes exceed the store bound {MLFQ_TREE_MAX_NODES}"
        ));
    }

    /* BFS from the root. Depth per node, rejecting the walk's cut shapes. */
    let mut depth = vec![usize::MAX; nr];
    depth[0] = 0;
    let mut queue = VecDeque::from([0usize]);
    while let Some(i) = queue.pop_front() {
        let node = &tree.nodes[i];
        if node.right == 0 {
            continue; /* leaf */
        }
        if node.feature >= MLFQ_TREE_NR_FEATURES as u8 {
            return Err(format!(
                "node {i} splits on feature {} beyond the {} populated slots",
                node.feature, MLFQ_TREE_NR_FEATURES
            ));
        }
        if depth[i] >= MLFQ_TREE_MAX_DEPTH {
            return Err(format!(
                "node {i} at depth {} is an internal node at or beyond the walk bound {MLFQ_TREE_MAX_DEPTH}",
                depth[i]
            ));
        }
        for child in [node.left, node.right] {
            let c = child as usize;
            if c >= nr {
                return Err(format!(
                    "node {i} child index {c} is out of range (nr_nodes {nr})"
                ));
            }
            if c <= i {
                return Err(format!(
                    "node {i} child index {c} precedes its parent, the BFS order is violated"
                ));
            }
            /*
             * Degenerate chains (left == right) are walked like any
             * other edge. The index ordering above makes cycles
             * impossible, so re-visiting a node only re-computes the
             * same depth.
             */
            if depth[c] == usize::MAX {
                depth[c] = depth[i] + 1;
                queue.push_back(c);
            }
        }
    }
    for (i, d) in depth.iter().enumerate() {
        if *d > MLFQ_TREE_MAX_DEPTH {
            return Err(format!(
                "node {i} sits at depth {d}, beyond the walk bound {MLFQ_TREE_MAX_DEPTH}"
            ));
        }
        if *d == usize::MAX {
            return Err(format!(
                "node {i} is not reachable from the root, the layout is not a tree"
            ));
        }
    }
    Ok(())
}

/// Walk a serialized tree and predict the next burst, the Rust mirror of
/// `mlfq_tree_walk()` in `src/bpf/intf.h` (the BPF wrapper adds only the
/// meta gate and the map lookup around this walk).
///
/// The walk descends at most `MLFQ_TREE_MAX_DEPTH` internal nodes, masking
/// every index with `MLFQ_TREE_MAX_NODES - 1`, splitting on
/// `feature & 0xF`, and returning `left` for a leaf (`right == 0`). A
/// masked index past the live nodes of an unpadded tree reads like a
/// zeroed store node (a leaf predicting 0). Depth exhausted, the last
/// reachable node's `left` is returned only when that node is a leaf; an
/// internal node there (a tree deeper than the bound) yields 0, matching
/// the BPF side.
///
/// An empty tree predicts 0, mirroring the untrained store.
pub fn predict(tree: &SerializedTree, feats: &TreeFeats) -> u64 {
    if tree.nodes.is_empty() {
        return 0; /* untrained */
    }

    let feat: [u64; 16] = [
        feats.prev_burst_ns,
        feats.sleep_ns,
        feats.ema,
        feats.io_wait as u64,
        feats.wake_cnt as u64,
        feats.wake_lat_us as u64,
        feats.queue_wait_us as u64,
        feats.sq_ema,
        feats.gpu_submit as u64,
        feats.sleep_var_ratio as u64,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let mask = MLFQ_TREE_MAX_NODES - 1;
    let mut idx = 0usize;

    for _ in 0..MLFQ_TREE_MAX_DEPTH {
        if idx >= tree.nodes.len() {
            return 0; /* zeroed store node: a leaf predicting 0 */
        }
        let node = &tree.nodes[idx];
        if node.right == 0 {
            return node.left as u64;
        }
        let feature = (node.feature & 0xF) as usize;
        let next = if feat[feature] <= node.threshold {
            node.left as usize
        } else {
            node.right as usize
        };
        idx = next & mask;
    }

    /* Depth exhausted. The last reachable node is the prediction only
     * when it is a leaf. An internal node here would leak a child index
     * as a prediction, so it yields 0. */
    if idx >= tree.nodes.len() {
        return 0;
    }
    let node = &tree.nodes[idx];
    if node.right == 0 {
        node.left as u64
    } else {
        0
    }
}

/// The publish quality gate. The tree replaces the previous model only when
/// its holdout MAE beats the exact per-sample EMA baseline on the same
/// holdout slice and the Pearson correlation clears the quality floor
/// and strictly improves on the currently committed model.
/// The holdout MAE is weighted by the recency weights of the window, so
/// recent samples dominate the gate. Correlation is monotonic: once a
/// model at 0.30 is committed, a later fit at 0.30 or below is held
/// out; 0.52 then 0.72 ratchet toward 1.0 on general workloads.
/// A higher correlation must also beat the baseline, so a high but
/// narrow fit on one game cannot regress the tail.
///
/// This is the daemon's contract with the README's claim that the tree
/// is published when it beats the baseline: a regressed model is kept
/// out and the previous model stays committed.
pub fn should_publish(mae_tree: f64, mae_ema: f64, corr: f64, published_corr: Option<f64>) -> bool {
    if mae_tree > mae_ema {
        return false;
    }
    if corr < 0.30 {
        return false;
    }
    if let Some(pc) = published_corr {
        if corr <= pc + 1e-9 {
            return false;
        }
    }
    true
}

/// Weighted MAE for the holdout slice. Each holdout sample carries its
/// recency weight w_i = 2^(-age_i / (n/2)) where n is the full window
/// length, so the gate emphasizes the recent regime without dropping
/// the older tail entirely.
pub fn weighted_holdout_mae(preds: &[u64], actuals: &[u64], weights: &[f64]) -> f64 {
    assert_eq!(preds.len(), actuals.len());
    assert_eq!(preds.len(), weights.len());
    if preds.is_empty() {
        return 0.0;
    }
    let mut sw = 0.0;
    let mut sw_err = 0.0;
    for ((p, a), w) in preds.iter().zip(actuals).zip(weights.iter()) {
        let err = if p >= a { *p - *a } else { *a - *p } as f64;
        sw += *w;
        sw_err += *w * err;
    }
    if sw == 0.0 {
        0.0
    } else {
        sw_err / sw
    }
}

/// Record-layout version tag of the emitted training samples, from
/// `enum mlfq_consts` in `src/bpf/intf.h`.
pub const MLFQ_TREE_SAMPLE_VERSION: u32 = crate::bpf_intf::mlfq_consts_MLFQ_TREE_SAMPLE_VERSION;

/// True when a parsed sample carries the current record-layout version.
///
/// The daemon and the BPF object compile from the same `intf.h`, so a
/// mismatch is either an out-of-tree producer or a stale build; the
/// check turns that into a loud drop at the parse instead of a silent
/// misread of the feature fields.
pub fn sample_version_matches(s: &TreeSample) -> bool {
    s.version == MLFQ_TREE_SAMPLE_VERSION
}

/// Bit position of the active-buffer flag in the committed-tree meta
/// (bit 1, the value of `MLFQ_TREE_META_ACTIVE`).
const MLFQ_TREE_META_ACTIVE_SHIFT: u32 = 1;

/// Serialize the committed-tree meta value from its parts.
///
/// The bit layout mirrors `struct mlfq_tree_ctrl` in `src/bpf/intf.h`:
/// bit 0 the trained bit (always set by a publish), bit 1 the active
/// buffer index, bits 8..31 the node count and bits 32..63 the
/// generation. The active bit is the caller's decision (the inactive
/// buffer index); the trained bit is constant because this function is
/// only used for a publish.
pub fn tree_meta(generation: u64, nr_nodes: usize, active: u64) -> u64 {
    /*
     * Mask the generation to its 32 meta bits before the shift. The
     * field is 32 bits wide and the wrap is unreachable (2^32 publishes
     * at the 60 s cadence is ~8200 years), so the mask is defensive
     * hygiene. It pins the shift input to the field width, so the
     * committed meta can never carry bits above the generation field
     * even if a caller passed an out-of-range value.
     */
    ((generation & 0xFFFF_FFFF) << crate::bpf_intf::MLFQ_TREE_META_GENERATION_SHIFT)
        | ((nr_nodes as u64) << crate::bpf_intf::MLFQ_TREE_META_NR_NODES_SHIFT)
        | ((active & 1) << MLFQ_TREE_META_ACTIVE_SHIFT)
        | crate::bpf_intf::MLFQ_TREE_META_TRAINED as u64
}

/// Mean absolute error between predictions and actuals.
///
/// Lengths must match. The empty case returns 0. The sums accumulate in
/// u128 so near-u64 values cannot overflow.
#[allow(dead_code)]
pub fn mae(preds: &[u64], actuals: &[u64]) -> f64 {
    assert_eq!(
        preds.len(),
        actuals.len(),
        "prediction and actual vectors differ in length"
    );
    if preds.is_empty() {
        return 0.0;
    }
    let total: u128 = preds
        .iter()
        .zip(actuals)
        .map(|(p, a)| (if p >= a { *p - *a } else { *a - *p }) as u128)
        .sum();
    total as f64 / preds.len() as f64
}

/// Pearson product-moment correlation of two equally long vectors.
///
/// Returns 0 for the empty case and for a constant vector (zero variance),
/// where the coefficient is undefined; keeping the metric finite lets the
/// daemon compare the tree against the EMA predictor without special
/// cases.
pub fn pearson(x: &[u64], y: &[u64]) -> f64 {
    assert_eq!(x.len(), y.len(), "correlation vectors differ in length");
    let n = x.len();
    if n == 0 {
        return 0.0;
    }

    let mean_x = x.iter().map(|v| *v as f64).sum::<f64>() / n as f64;
    let mean_y = y.iter().map(|v| *v as f64).sum::<f64>() / n as f64;

    let (mut cov, mut var_x, mut var_y) = (0.0, 0.0, 0.0);
    for (xi, yi) in x.iter().zip(y) {
        let dx = *xi as f64 - mean_x;
        let dy = *yi as f64 - mean_y;
        cov += dx * dy;
        var_x += dx * dx;
        var_y += dy * dy;
    }
    if var_x == 0.0 || var_y == 0.0 {
        return 0.0;
    }
    cov / (var_x * var_y).sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift64* PRNG so the datasets are reproducible.
    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn next_in(&mut self, lo: u64, hi: u64) -> u64 {
            lo + self.next_u64() % (hi - lo)
        }
    }

    fn sample(pid: u32, sleep_ns: u64, label_ns: u64) -> TreeSample {
        TreeSample {
            pid,
            version: MLFQ_TREE_SAMPLE_VERSION,
            queue: 1,
            feats: TreeFeats {
                sleep_ns,
                ..TreeFeats::default()
            },
            label_ns,
        }
    }

    /// The mirror of `predict()` that returns the terminal node index, so
    /// tests can reconstruct which training samples share a leaf.
    fn leaf_index(tree: &SerializedTree, feats: &TreeFeats) -> usize {
        let feat: [u64; 16] = [
            feats.prev_burst_ns,
            feats.sleep_ns,
            feats.ema,
            feats.io_wait as u64,
            feats.wake_cnt as u64,
            feats.wake_lat_us as u64,
            feats.queue_wait_us as u64,
            feats.sq_ema,
            feats.gpu_submit as u64,
            feats.sleep_var_ratio as u64,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mask = MLFQ_TREE_MAX_NODES - 1;
        let mut idx = 0usize;
        for _ in 0..MLFQ_TREE_MAX_DEPTH {
            if idx >= tree.nodes.len() {
                return idx;
            }
            let node = &tree.nodes[idx];
            if node.right == 0 {
                return idx;
            }
            let feature = (node.feature & 0xF) as usize;
            let next = if feat[feature] <= node.threshold {
                node.left as usize
            } else {
                node.right as usize
            };
            idx = next & mask;
        }
        idx
    }

    #[test]
    fn separable_dataset_recovers_split() {
        // Two classes separated by sleep: ~500us sleeps burst ~= 100us,
        // ~2ms sleeps burst ~= 10ms, both with deterministic jitter. Only
        // sleep_ns carries signal, so the root must split on it and the
        // threshold must sit between the two class regions.
        let mut rng = Rng(0xC0FFEE);
        let mut samples = Vec::new();
        for pid in 0..512u32 {
            let interactive = pid % 2 == 0;
            let sleep = if interactive { 500_000 } else { 2_000_000 };
            let sleep = sleep + rng.next_in(0, 100_000);
            let label = if interactive { 100_000 } else { 10_000_000 };
            let label = label + rng.next_in(0, 10_000);
            samples.push(sample(pid, sleep, label));
        }

        let tree = fit(&samples, 12, 2, 63, DEFAULT_MIN_REL_VAR_REDUCTION);
        serialize_validate(&tree).unwrap();

        let root = &tree.nodes[0];
        assert!(root.right != 0, "the root must be an internal node");
        assert_eq!(root.feature, 1, "the root must split on sleep_ns");
        assert!(
            root.threshold > 1_000_000 && root.threshold < 1_500_000,
            "root threshold {} must sit between the class regions",
            root.threshold
        );

        // The leaf predictions must separate the classes.
        for s in &samples {
            let feats = s.feats;
            let pred = predict(&tree, &feats);
            if s.feats.sleep_ns < 1_000_000 {
                assert!(
                    (90_000..=110_000).contains(&pred),
                    "interactive sample predicted {pred}"
                );
            } else {
                assert!(
                    (9_900_000..=10_100_000).contains(&pred),
                    "CPU-bound sample predicted {pred}"
                );
            }
        }
    }

    #[test]
    fn irrelevant_feature_never_split_on() {
        // wake_cnt (feature 4) is uniform noise over a wide range; the
        // label depends only on sleep_ns, and exactly (no label noise), so
        // no split on wake_cnt can reduce the variance at all after the
        // sleep split. The tree must never split on feature 4.
        let mut rng = Rng(0xBEEF);
        let mut samples = Vec::new();
        for pid in 0..1024u32 {
            let interactive = pid % 2 == 0;
            let sleep = if interactive { 500_000 } else { 2_000_000 };
            let label = if interactive { 100_000 } else { 10_000_000 };
            let wake_cnt = rng.next_in(0, 1_000_000);
            let mut s = sample(pid, sleep, label);
            s.feats.wake_cnt = wake_cnt as u32;
            samples.push(s);
        }

        let tree = fit(&samples, 4, 2, 127, DEFAULT_MIN_REL_VAR_REDUCTION);
        serialize_validate(&tree).unwrap();

        for (i, node) in tree.nodes.iter().enumerate() {
            if node.right != 0 {
                assert_ne!(
                    node.feature, 4,
                    "node {i} must not split on the irrelevant wake_cnt"
                );
            }
        }
    }

    #[test]
    fn depth_and_min_leaf_caps_respected() {
        // A staircase label (label == sleep) forces repeated splitting:
        // with min_rel_var_reduction 0 the tree grows greedily until the
        // depth or leaf caps stop it. All leaves must hold at least
        // min_samples_leaf training samples and no internal node may sit
        // below the depth cap.
        let mut samples = Vec::new();
        for (i, sleep) in (100_000u64..1_700_000).step_by(100_000).enumerate() {
            for k in 0..4 {
                let mut s = sample(i as u32 + k, sleep, sleep);
                s.feats.prev_burst_ns = 50_000 + 10_000 * (i % 5) as u64;
                samples.push(s);
            }
        }

        let max_depth = 3;
        let min_samples_leaf = 2;
        let tree = fit(&samples, max_depth, min_samples_leaf, 1000, 0.0);
        serialize_validate(&tree).unwrap();

        // Depth of every node in the BFS layout, computed from the parents.
        let mut depth = vec![0usize; tree.nodes.len()];
        for (i, node) in tree.nodes.iter().enumerate() {
            if node.right != 0 {
                assert!(
                    depth[i] < max_depth,
                    "node {i} at depth {} exceeds the cap {max_depth}",
                    depth[i]
                );
                depth[node.left as usize] = depth[i] + 1;
                depth[node.right as usize] = depth[i] + 1;
            }
        }

        // Every leaf receives at least min_samples_leaf training samples.
        let mut leaf_counts = std::collections::HashMap::new();
        for s in &samples {
            let feats = s.feats;
            *leaf_counts
                .entry(leaf_index(&tree, &feats))
                .or_insert(0usize) += 1;
        }
        assert!(!leaf_counts.is_empty(), "the tree must have leaves");
        for (leaf, count) in &leaf_counts {
            assert!(
                *count >= min_samples_leaf,
                "leaf {leaf} holds {count} samples, below the cap {min_samples_leaf}"
            );
        }
    }

    #[test]
    fn serialize_walk_roundtrip() {
        // The walk over the serialized tree must return, for every
        // training sample, the recency-weighted mean of the labels
        // routed to the sample's leaf: the expected value of the
        // weighted fit.
        let mut rng = Rng(0xABCDEF);
        let mut samples = Vec::new();
        for pid in 0..1024u32 {
            let interactive = pid % 3 == 0;
            let sleep = if interactive { 400_000 } else { 2_500_000 };
            let sleep = sleep + rng.next_in(0, 50_000);
            let label = if interactive { 80_000 } else { 12_000_000 };
            let label = label + rng.next_in(0, 200_000);
            samples.push(sample(pid, sleep, label));
        }

        let tree = fit(&samples, 8, 4, 511, DEFAULT_MIN_REL_VAR_REDUCTION);
        serialize_validate(&tree).unwrap();

        let n = samples.len();
        let half_life = n as f64 / 2.0;
        let weight_of = |i: usize| 2.0f64.powf(-((n - i) as f64) / half_life);

        for s in &samples {
            let feats = s.feats; /* copy out of the packed sample */
            let leaf = leaf_index(&tree, &feats);
            let mut wsum = 0.0f64;
            let mut wsum_y = 0.0f64;
            for (j, t) in samples.iter().enumerate() {
                let t_feats = t.feats;
                if leaf_index(&tree, &t_feats) == leaf {
                    wsum += weight_of(j);
                    wsum_y += weight_of(j) * t.label_ns as f64;
                }
            }
            let expected = leaf_prediction((wsum_y / wsum) as u64) as u64;
            let pid = s.pid;
            assert_eq!(
                predict(&tree, &feats),
                expected,
                "round-trip prediction for pid {} via leaf {leaf}",
                pid
            );
        }
    }

    #[test]
    fn holdout_mae_beats_constant_mean() {
        // A tree trained on two thirds of the data must beat the
        // constant-mean predictor on the held-out third.
        let mut rng = Rng(0x1234_5678);
        let mut samples = Vec::new();
        for pid in 0..1200u32 {
            let interactive = pid % 2 == 0;
            let sleep = if interactive { 300_000 } else { 3_000_000 };
            let sleep = sleep + rng.next_in(0, 100_000);
            let label = if interactive { 120_000 } else { 15_000_000 };
            let label = label + rng.next_in(0, 500_000);
            samples.push(sample(pid, sleep, label));
        }

        let split = 2 * samples.len() / 3;
        let (train, test) = samples.split_at(split);
        let tree = fit(train, 8, 4, 511, DEFAULT_MIN_REL_VAR_REDUCTION);
        serialize_validate(&tree).unwrap();

        let actuals: Vec<u64> = test.iter().map(|s| s.label_ns).collect();
        let preds: Vec<u64> = test
            .iter()
            .map(|s| {
                let feats = s.feats;
                predict(&tree, &feats)
            })
            .collect();
        let mae_tree = mae(&preds, &actuals);

        let mean_label = train.iter().map(|s| s.label_ns as f64).sum::<f64>() / train.len() as f64;
        let const_preds = vec![mean_label as u64; test.len()];
        let mae_const = mae(&const_preds, &actuals);

        assert!(
            mae_tree < mae_const,
            "tree MAE {mae_tree} must beat the constant-mean MAE {mae_const}"
        );
    }

    #[test]
    fn empty_input_errors() {
        let tree = fit(&[], 4, 2, 63, DEFAULT_MIN_REL_VAR_REDUCTION);
        assert!(tree.nodes.is_empty(), "an empty fit yields no nodes");
        assert!(
            serialize_validate(&tree).is_err(),
            "an empty tree must not validate"
        );
        assert_eq!(predict(&tree, &TreeFeats::default()), 0);

        // Zero node budget: same empty shape.
        let s = sample(0, 1_000, 1_000);
        let tree = fit(&[s], 4, 2, 0, DEFAULT_MIN_REL_VAR_REDUCTION);
        assert!(tree.nodes.is_empty());
        assert!(serialize_validate(&tree).is_err());

        // Length mismatch is a caller bug and must be loud.
        assert_eq!(mae(&[], &[]), 0.0);
        assert_eq!(pearson(&[], &[]), 0.0);
    }

    #[test]
    fn threshold_roundtrip_u64_precision() {
        // Two classes separated by a sleep gap just below u64::MAX: the
        // stored threshold must be the exact overflow-safe midpoint and
        // the walk must route on it without wrapping.
        let lo = u64::MAX - 1_000_000;
        let hi = u64::MAX - 100_000;
        let mut samples = Vec::new();
        for k in 0..4 {
            let mut a = sample(k, lo, 100_000);
            a.feats.prev_burst_ns = 1_000; /* constant across classes */
            let mut b = sample(k + 4, hi, 10_000_000);
            b.feats.prev_burst_ns = 1_000;
            samples.push(a);
            samples.push(b);
        }

        let tree = fit(&samples, 4, 2, 31, DEFAULT_MIN_REL_VAR_REDUCTION);
        serialize_validate(&tree).unwrap();

        let root = &tree.nodes[0];
        assert_eq!(root.feature, 1, "the root must split on sleep_ns");
        assert_eq!(root.threshold, lo + (hi - lo) / 2);

        for s in &samples {
            let feats = s.feats;
            let pid = s.pid;
            let pred = predict(&tree, &feats);
            let expected = if s.feats.sleep_ns == lo {
                100_000
            } else {
                10_000_000
            };
            assert_eq!(pred, expected, "pid {}", pid);
        }

        // Consecutive distinct values collapse to the lower one, which
        // still separates them (lower routes left, higher routes right).
        let samples = [sample(0, 100, 1_000), sample(1, 101, 9_000)];
        let tree = fit(&samples, 4, 1, 31, DEFAULT_MIN_REL_VAR_REDUCTION);
        serialize_validate(&tree).unwrap();
        assert_eq!(tree.nodes[0].threshold, 100);
        let f0 = samples[0].feats;
        let f1 = samples[1].feats;
        assert_eq!(predict(&tree, &f0), 1_000);
        assert_eq!(predict(&tree, &f1), 9_000);
    }

    #[test]
    fn validate_rejects_broken_trees() {
        // Two samples with distinct sleep make the root an internal node.
        let samples = [sample(0, 100, 1_000), sample(1, 101, 9_000)];
        let fit_ok = |min_rel: f64| fit(&samples, 4, 1, 31, min_rel);
        assert!(serialize_validate(&fit_ok(0.0)).is_ok());

        // Internal node splitting on feature 9 (beyond NR_FEATURES 9).
        let mut bad = fit_ok(0.0);
        bad.nodes[0].feature = 9;
        assert!(serialize_validate(&bad).is_err());

        // Child index out of range.
        let mut bad = fit_ok(0.0);
        bad.nodes[0].right = MLFQ_TREE_MAX_NODES as u32;
        assert!(serialize_validate(&bad).is_err());

        // Child preceding its parent (BFS order violation).
        let mut bad = fit_ok(0.0);
        bad.nodes[0].left = 0;
        assert!(serialize_validate(&bad).is_err());

        // A larger fit passes.
        let mut samples = Vec::new();
        for pid in 0..64u32 {
            let sleep = if pid % 2 == 0 { 400_000 } else { 2_500_000 };
            let label = if pid % 2 == 0 { 80_000 } else { 12_000_000 };
            samples.push(sample(pid, sleep, label));
        }
        let tree = fit(&samples, 4, 2, 63, DEFAULT_MIN_REL_VAR_REDUCTION);
        assert!(serialize_validate(&tree).is_ok());
    }

    #[test]
    fn metrics_on_known_vectors() {
        assert_eq!(mae(&[10, 20], &[12, 18]), 2.0);
        assert_eq!(mae(&[1_000], &[2_000]), 1_000.0);

        // Perfectly correlated vectors give 1.0, anticorrelated -1.0,
        // orthogonal ~0.0 (the last with tolerance).
        let x = [1, 2, 3, 4];
        let y = [10, 20, 30, 40];
        assert!((pearson(&x, &y) - 1.0).abs() < 1e-12);
        assert!((pearson(&x, &[40, 30, 20, 10]) + 1.0).abs() < 1e-12);
        assert!(pearson(&x, &[1, 4, 4, 1]).abs() < 1e-12);

        // A constant vector has undefined correlation; the metric stays 0.
        assert_eq!(pearson(&x, &[5, 5, 5, 5]), 0.0);
    }

    #[test]
    fn publish_gate_and_tree_meta() {
        // The gate requires MAE_tree <= MAE_ema and corr >=0.30, and once
        // a model is committed its correlation must be strictly exceeded
        // (monotonic ratchet toward 1.0). A regressed MAE or a non-
        // improving correlation keeps the previous model.
        assert!(should_publish(100.0, 100.0, 0.5, None));
        assert!(should_publish(99.0, 100.0, 0.5, None));
        assert!(!should_publish(101.0, 100.0, 0.5, None));
        assert!(should_publish(0.0, 0.0, 0.5, None));
        assert!(!should_publish(90.0, 100.0, 0.29, None));
        assert!(should_publish(90.0, 100.0, 0.30, None));
        assert!(!should_publish(90.0, 100.0, 0.0, None));
        assert!(!should_publish(90.0, 100.0, 0.30, Some(0.30)));
        assert!(should_publish(90.0, 100.0, 0.31, Some(0.30)));
        assert!(!should_publish(90.0, 100.0, 0.50, Some(0.50)));
        assert!(should_publish(90.0, 100.0, 0.52, Some(0.50)));
        assert!(should_publish(90.0, 100.0, 0.72, Some(0.52)));
        // Weighted holdout: recent samples dominate.
        let preds = [100, 200];
        let actuals = [110, 190];
        let w = [0.25, 1.0];
        let wm = weighted_holdout_mae(&preds, &actuals, &w);
        assert!((wm - 10.0).abs() < 1e-9);

        // The meta bits are exact: trained bit 0 (always set by a
        // publish), active bit 1, node count in bits 8..31 and the
        // generation in bits 32..63.
        assert_eq!(tree_meta(0, 1, 0), (1 << 8) | 1);
        assert_eq!(tree_meta(0, 2048, 1), (2048 << 8) | (1 << 1) | 1);
        let m = tree_meta(3, 7, 0);
        assert_eq!(m, (3u64 << 32) | (7 << 8) | 1);
        assert_eq!(
            m & crate::bpf_intf::MLFQ_TREE_META_TRAINED as u64,
            crate::bpf_intf::MLFQ_TREE_META_TRAINED as u64
        );
        assert_eq!((m >> 1) & 1, 0);
        assert_eq!((m >> 8) & 0xFFFFFF, 7);
        assert_eq!(m >> 32, 3);
        // The active bit flips the entry the walk reads.
        assert_eq!((tree_meta(0, 1, 1) >> 1) & 1, 1);

        // The generation is masked to its 32 meta bits before the shift:
        // an out-of-range value must not overflow the shift (debug builds
        // would panic), and the mask keeps the field semantics exact.
        assert_eq!(tree_meta(0x1_0000_0000, 1, 0), (1 << 8) | 1);
        assert_eq!(
            tree_meta(0xFFFF_FFFF_FFFF_FFFF, 0, 0),
            0xFFFF_FFFF_0000_0000 | 1
        );
        assert_eq!(tree_meta(0x1_FFFF_FFFF, 1, 0), 0xFFFF_FFFF_0000_0101);
    }

    #[test]
    fn predict_depth_exhaustion_yields_zero_on_internal() {
        // A chain of MLFQ_TREE_MAX_DEPTH + 1 internal nodes: the walk
        // descends the first 12 edges and stops, and the node it lands
        // on (depth 12) is internal, so the prediction must be 0. A
        // child index must never leak out as a burst.
        let mut tree = SerializedTree::default();
        for i in 0..=MLFQ_TREE_MAX_DEPTH {
            tree.nodes.push(TreeNode {
                threshold: 0,
                left: (i + 1) as u32,
                right: (i + 1) as u32,
                feature: 0,
                pad: [0; 7],
            });
        }
        assert_eq!(predict(&tree, &TreeFeats::default()), 0);
        // Such a tree is deeper than the walk bound: the validator
        // rejects the internal node at depth 12.
        assert!(serialize_validate(&tree).is_err());

        // A chain that ends in a leaf exactly at the bound is valid and
        // predicts the leaf.
        let mut tree = SerializedTree::default();
        for i in 0..MLFQ_TREE_MAX_DEPTH {
            tree.nodes.push(TreeNode {
                threshold: 0,
                left: (i + 1) as u32,
                right: (i + 1) as u32,
                feature: 0,
                pad: [0; 7],
            });
        }
        tree.nodes.push(TreeNode {
            threshold: 0,
            left: 777_777,
            right: 0,
            feature: 0,
            pad: [0; 7],
        });
        assert!(serialize_validate(&tree).is_ok());
        assert_eq!(predict(&tree, &TreeFeats::default()), 777_777);
    }

    #[test]
    fn serialize_validate_rejects_deep_trees() {
        // A leaf at depth 13 needs an internal parent at depth 12, which
        // the walk can only ever reach through the exhaustion fallback;
        // the validator rejects the internal-at-the-bound shape.
        let mut tree = SerializedTree::default();
        for i in 0..=MLFQ_TREE_MAX_DEPTH {
            tree.nodes.push(TreeNode {
                threshold: 0,
                left: (i + 1) as u32,
                right: (i + 1) as u32,
                feature: 0,
                pad: [0; 7],
            });
        }
        tree.nodes.push(TreeNode {
            threshold: 0,
            left: 42,
            right: 0,
            feature: 0,
            pad: [0; 7],
        });
        assert!(serialize_validate(&tree).is_err());
    }

    #[test]
    fn adversarial_constant_labels_never_split() {
        // All labels identical: the SSE is exactly 0, so no split can
        // reduce it and the tree must be a single leaf predicting the
        // constant.
        let samples: Vec<TreeSample> = (0..64u32)
            .map(|pid| sample(pid, 1_000_000, 123_456))
            .collect();
        let tree = fit(&samples, 12, 2, 2048, 0.0);
        assert_eq!(tree.nodes.len(), 1, "a constant label set yields one leaf");
        assert_eq!(tree.nodes[0].right, 0);
        let feats = samples[0].feats;
        assert_eq!(predict(&tree, &feats), 123_456);
        serialize_validate(&tree).unwrap();
    }

    #[test]
    fn adversarial_max_nodes_exhaustion_mid_growth() {
        // Staircase labels force repeated splitting; a node budget of 3
        // must stop the growth right after the root split, leaving two
        // leaves.
        let mut samples = Vec::new();
        for (i, sleep) in (100_000u64..700_000).step_by(100_000).enumerate() {
            for k in 0..4 {
                let mut s = sample(i as u32 + k, sleep, sleep);
                s.feats.prev_burst_ns = 1_000;
                samples.push(s);
            }
        }
        let tree = fit(&samples, 12, 1, 3, 0.0);
        assert_eq!(
            tree.nodes.len(),
            3,
            "max_nodes 3 caps the growth at root + two leaves"
        );
        assert!(tree.nodes[0].right != 0);
        assert_eq!(tree.nodes[1].right, 0);
        assert_eq!(tree.nodes[2].right, 0);
        serialize_validate(&tree).unwrap();
    }

    #[test]
    fn adversarial_extreme_labels_clamp() {
        // Labels at the top of the u64 range: the f64 SSE math must not
        // misbehave, and the leaf mean saturates through leaf_prediction
        // to u32::MAX (the walk returns the field as-is).
        let mut samples = Vec::new();
        for k in 0..4 {
            let mut a = sample(k, 100_000, u64::MAX);
            a.feats.prev_burst_ns = 1_000;
            let mut b = sample(k + 4, 200_000, 0);
            b.feats.prev_burst_ns = 1_000;
            samples.push(a);
            samples.push(b);
        }
        let tree = fit(&samples, 4, 2, 31, DEFAULT_MIN_REL_VAR_REDUCTION);
        serialize_validate(&tree).unwrap();
        assert_eq!(tree.nodes[0].feature, 1, "the root must split on sleep_ns");
        assert_eq!(
            predict(
                &tree,
                &TreeFeats {
                    prev_burst_ns: 1_000,
                    sleep_ns: 100_000,
                    ..TreeFeats::default()
                }
            ),
            u32::MAX as u64,
            "the extreme class clamps to the u32 leaf field"
        );
        assert_eq!(
            predict(
                &tree,
                &TreeFeats {
                    prev_burst_ns: 1_000,
                    sleep_ns: 200_000,
                    ..TreeFeats::default()
                }
            ),
            0
        );
    }

    #[test]
    fn adversarial_min_leaf_boundary() {
        // n == 2*min_samples_leaf splits (both children reach the leaf
        // cap); n == 2*min_samples_leaf - 1 does not, because the left
        // group would fall below the cap.
        let class_a: Vec<TreeSample> = (0..3u32).map(|pid| sample(pid, 100_000, 100_000)).collect();
        let class_b: Vec<TreeSample> = (3..6u32).map(|pid| sample(pid, 200_000, 900_000)).collect();
        let mut samples = class_a.clone();
        samples.extend(class_b.iter().copied());
        let tree = fit(&samples, 4, 3, 31, 0.0);
        assert!(tree.nodes[0].right != 0, "n == 2*min_samples_leaf splits");
        serialize_validate(&tree).unwrap();

        let samples = [class_a[0], class_a[1], class_b[0], class_b[1], class_b[2]];
        let tree = fit(&samples, 4, 3, 31, 0.0);
        assert_eq!(
            tree.nodes.len(),
            1,
            "n == 2*min_samples_leaf - 1 leaves one child below the cap: no split"
        );
    }

    #[test]
    fn golden_tree_predict_matches_shared_spec() {
        // The shared crafted tree walked by both the native harness
        // (test_tree_golden_shared in mlfq_math_test.c) and this Rust
        // mirror, with identical expected outputs: a chain on
        // prev_burst_ns, mixed leaves, and a node whose raw feature id
        // is out of the populated range but masks in-bounds (0x84 ->
        // 4 = wake_cnt). The tree is a walk spec, not a publish spec.
        // The raw feature above 4 means serialize_validate rejects it,
        // and published trees are validated before the walk sees them.
        let nodes = vec![
            TreeNode {
                threshold: 1_000_000,
                left: 1,
                right: 8,
                feature: 0,
                pad: [0; 7],
            },
            TreeNode {
                threshold: 1_000_000,
                left: 2,
                right: 8,
                feature: 0,
                pad: [0; 7],
            },
            TreeNode {
                threshold: 1_000_000,
                left: 3,
                right: 8,
                feature: 0,
                pad: [0; 7],
            },
            TreeNode {
                threshold: 500_000,
                left: 4,
                right: 5,
                feature: 1,
                pad: [0; 7],
            },
            TreeNode {
                threshold: 0,
                left: 1_111_111,
                right: 0,
                feature: 0,
                pad: [0; 7],
            },
            TreeNode {
                threshold: 1,
                left: 6,
                right: 7,
                feature: 0x84,
                pad: [0; 7],
            },
            TreeNode {
                threshold: 0,
                left: 2_222_222,
                right: 0,
                feature: 0,
                pad: [0; 7],
            },
            TreeNode {
                threshold: 0,
                left: 3_333_333,
                right: 0,
                feature: 0,
                pad: [0; 7],
            },
            TreeNode {
                threshold: 0,
                left: 8_888_888,
                right: 0,
                feature: 0,
                pad: [0; 7],
            },
        ];
        let tree = SerializedTree { nodes };

        let f = |prev: u64, sleep: u64, wake: u32| TreeFeats {
            prev_burst_ns: prev,
            sleep_ns: sleep,
            wake_cnt: wake,
            ..TreeFeats::default()
        };
        assert_eq!(predict(&tree, &f(0, 400_000, 0)), 1_111_111);
        assert_eq!(predict(&tree, &f(0, 600_000, 0)), 2_222_222);
        assert_eq!(predict(&tree, &f(0, 600_000, 5)), 3_333_333);
        assert_eq!(predict(&tree, &f(2_000_000, 0, 0)), 8_888_888);
        // wake_cnt is irrelevant on the sleep split's left branch.
        assert_eq!(predict(&tree, &f(0, 400_000, 9)), 1_111_111);
    }

    #[test]
    fn abi_layout_matches_bpf_structs() {
        // The Rust structs are the byte-for-byte mirrors of the BPF
        // types in src/bpf/intf.h (via the bindgen-generated bpf_intf):
        // the ring-buffer records are parsed straight into TreeSample
        // and the serialized nodes are written straight into the store
        // map entry, so the sizes and offsets must match exactly.
        use crate::bpf_intf::{mlfq_tree_feats, mlfq_tree_node, mlfq_tree_sample};
        use std::mem::{offset_of, size_of};

        assert_eq!(size_of::<TreeFeats>(), size_of::<mlfq_tree_feats>());
        assert_eq!(size_of::<TreeNode>(), size_of::<mlfq_tree_node>());
        assert_eq!(size_of::<TreeSample>(), size_of::<mlfq_tree_sample>());
        assert_eq!(size_of::<TreeFeats>(), 64);
        assert_eq!(size_of::<TreeSample>(), 84);
        assert_eq!(size_of::<TreeNode>(), 24);

        assert_eq!(
            offset_of!(TreeFeats, prev_burst_ns),
            offset_of!(mlfq_tree_feats, prev_burst_ns)
        );
        assert_eq!(
            offset_of!(TreeFeats, sleep_ns),
            offset_of!(mlfq_tree_feats, sleep_ns)
        );
        assert_eq!(offset_of!(TreeFeats, ema), offset_of!(mlfq_tree_feats, ema));
        assert_eq!(
            offset_of!(TreeFeats, io_wait),
            offset_of!(mlfq_tree_feats, io_wait)
        );
        assert_eq!(
            offset_of!(TreeFeats, wake_cnt),
            offset_of!(mlfq_tree_feats, wake_cnt)
        );
        assert_eq!(
            offset_of!(TreeFeats, wake_lat_us),
            offset_of!(mlfq_tree_feats, wake_lat_us)
        );
        assert_eq!(
            offset_of!(TreeFeats, queue_wait_us),
            offset_of!(mlfq_tree_feats, queue_wait_us)
        );
        assert_eq!(
            offset_of!(TreeFeats, sq_ema),
            offset_of!(mlfq_tree_feats, sq_ema)
        );
        assert_eq!(
            offset_of!(TreeFeats, sleep_var_ratio),
            offset_of!(mlfq_tree_feats, sleep_var_ratio)
        );
        assert_eq!(
            offset_of!(TreeFeats, gpu_submit),
            offset_of!(mlfq_tree_feats, gpu_submit)
        );
        assert_eq!(offset_of!(TreeFeats, wake_lat_us), 32);
        assert_eq!(offset_of!(TreeFeats, queue_wait_us), 36);
        assert_eq!(offset_of!(TreeFeats, sq_ema), 40);
        assert_eq!(offset_of!(TreeFeats, sleep_var_ratio), 48);
        assert_eq!(offset_of!(TreeFeats, pad), 52);
        assert_eq!(offset_of!(TreeFeats, gpu_submit), 56);
        assert_eq!(offset_of!(TreeFeats, pad2), 60);

        assert_eq!(
            offset_of!(TreeNode, threshold),
            offset_of!(mlfq_tree_node, threshold)
        );
        assert_eq!(offset_of!(TreeNode, left), offset_of!(mlfq_tree_node, left));
        assert_eq!(
            offset_of!(TreeNode, right),
            offset_of!(mlfq_tree_node, right)
        );
        assert_eq!(
            offset_of!(TreeNode, feature),
            offset_of!(mlfq_tree_node, feature)
        );
        assert_eq!(offset_of!(TreeNode, feature), 16);
        assert_eq!(offset_of!(TreeNode, pad), offset_of!(mlfq_tree_node, pad));
        assert_eq!(offset_of!(TreeNode, pad), 17);

        assert_eq!(
            offset_of!(TreeSample, pid),
            offset_of!(mlfq_tree_sample, pid)
        );
        assert_eq!(
            offset_of!(TreeSample, queue),
            offset_of!(mlfq_tree_sample, queue)
        );
        assert_eq!(
            offset_of!(TreeSample, feats),
            offset_of!(mlfq_tree_sample, feats)
        );
        assert_eq!(
            offset_of!(TreeSample, label_ns),
            offset_of!(mlfq_tree_sample, label_ns)
        );
        assert_eq!(
            offset_of!(TreeSample, version),
            offset_of!(mlfq_tree_sample, version)
        );
        assert_eq!(offset_of!(TreeSample, queue), 4);
        assert_eq!(offset_of!(TreeSample, feats), 8);
        assert_eq!(offset_of!(TreeSample, label_ns), 72);
        assert_eq!(offset_of!(TreeSample, version), 80);
    }

    #[test]
    fn sample_version_tag_is_checked() {
        // The version tag distinguishes a current-format record from a
        // foreign or stale one: the parse check accepts exactly the
        // compiled-in version and nothing else.
        let cur = TreeSample {
            pid: 1,
            version: MLFQ_TREE_SAMPLE_VERSION,
            queue: 2,
            feats: TreeFeats::default(),
            label_ns: 0,
        };
        assert!(sample_version_matches(&cur));

        let stale = TreeSample { version: 0, ..cur };
        assert!(!sample_version_matches(&stale));
        let future = TreeSample {
            version: MLFQ_TREE_SAMPLE_VERSION + 1,
            ..cur
        };
        assert!(!sample_version_matches(&future));
    }

    #[test]
    fn recency_weights_pin_the_ends() {
        // The recency weighting formula: the newest sample weighs ~1 and
        // the oldest exactly 0.25, so the admitted window cannot
        // underflow and the recent regime dominates the fit.
        let n = 8;
        let half_life = n as f64 / 2.0;
        let w_newest = 2.0f64.powf(-1.0 / half_life);
        let w_oldest = 2.0f64.powf(-(n as f64) / half_life);
        assert!((w_oldest - 0.25).abs() < 1e-15);
        assert!((w_newest - 1.0).abs() < 0.2);

        let ws = sample_weights(n);
        assert_eq!(ws.len(), n);
        assert!((ws[0] - w_oldest).abs() < 1e-15);
        assert!((ws[n - 1] - w_newest).abs() < 1e-15);
        // Strictly increasing toward the newest.
        for i in 0..n - 1 {
            assert!(ws[i] < ws[i + 1]);
        }
    }
}
