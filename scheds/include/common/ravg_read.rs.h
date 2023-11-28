/// ravg_read() implementation for rust userland. See ravg_read() in
/// ravg_impl.bpf.h. We don't yet have a good mechanism to share BPF and
/// matching rust code across multiple schedulers. For now, include both BPF
/// and rust code from scheduler implementations.
fn ravg_read(
    val: u64,
    val_at: u64,
    old: u64,
    cur: u64,
    now: u64,
    half_life: u32,
    frac_bits: u32,
) -> f64 {
    let ravg_1: f64 = (1 << frac_bits) as f64;
    let half_life = half_life as u64;
    let val = val as f64;
    let mut old = old as f64 / ravg_1;
    let mut cur = cur as f64 / ravg_1;

    let now = now.max(val_at);
    let normalized_dur = |dur| dur as f64 / half_life as f64;

    //
    // The following is f64 implementation of BPF ravg_accumulate().
    //
    let cur_seq = (now / half_life) as i64;
    let val_seq = (val_at / half_life) as i64;
    let seq_delta = (cur_seq - val_seq) as i32;

    if seq_delta > 0 {
        let full_decay = 2f64.powi(seq_delta);

        // Decay $old and fold $cur into it.
        old /= full_decay;
        old += cur / full_decay;
        cur = 0.0;

        // Fold the oldest period whicy may be partial.
        old += val * normalized_dur(half_life - val_at % half_life) / full_decay;

        // Pre-computed decayed full-period values.
        const FULL_SUMS: [f64; 20] = [
            0.5,
            0.75,
            0.875,
            0.9375,
            0.96875,
            0.984375,
            0.9921875,
            0.99609375,
            0.998046875,
            0.9990234375,
            0.99951171875,
            0.999755859375,
            0.9998779296875,
            0.99993896484375,
            0.999969482421875,
            0.9999847412109375,
            0.9999923706054688,
            0.9999961853027344,
            0.9999980926513672,
            0.9999990463256836,
            // Use the same value beyond this point.
        ];

        // Fold the full periods in the middle.
        if seq_delta >= 2 {
            let idx = ((seq_delta - 2) as usize).min(FULL_SUMS.len() - 1);
            old += val * FULL_SUMS[idx];
        }

        // Accumulate the current period duration into @cur.
        cur += val * normalized_dur(now % half_life);
    } else {
        cur += val * normalized_dur(now - val_at);
    }

    //
    // The following is the blending part of BPF ravg_read().
    //
    old * (1.0 - normalized_dur(now % half_life) / 2.0) + cur / 2.0
}
