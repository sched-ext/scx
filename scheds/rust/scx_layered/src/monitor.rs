use crate::SysStats;
use anyhow::Result;
use log::info;
use log::warn;
use scx_stats::ScxStatsClient;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

fn print_sys_stats(s: &SysStats) {
    let fmt_pct = |v: f64| {
        if v >= 99.995 {
            format!("{:5.1}", v)
        } else {
            format!("{:5.2}", v)
        }
    };

    let fmt_num = |v: u64| {
        if v > 1_000_000 {
            format!("{:5.1}m", v as f64 / 1_000_000.0)
        } else if v > 1_000 {
            format!("{:5.1}k", v as f64 / 1_000.0)
        } else {
            format!("{:5.0} ", v)
        }
    };

    info!(
        "tot={:7} local={} open_idle={} affn_viol={} proc={:?}ms",
        s.total,
        fmt_pct(s.local),
        fmt_pct(s.open_idle),
        fmt_pct(s.affn_viol),
        s.proc_ms,
    );

    info!(
        "busy={:5.1} util={:7.1} load={:9.1} fallback_cpu={:3}",
        s.busy, s.util, s.load, s.fallback_cpu,
    );

    info!(
        "excl_coll={} excl_preempt={} excl_idle={} excl_wakeup={}",
        s.excl_collision, s.excl_preempt, s.excl_idle, s.excl_wakeup
    );

    let header_width = s
        .layers
        .keys()
        .map(|name| name.len())
        .max()
        .unwrap_or(0)
        .max(4);

    for (name, l) in s.layers.iter() {
        info!(
            "  {:<width$}: util/frac={:7.1}/{:5.1} load/frac={:9.1}:{:5.1} tasks={:6}",
            name,
            l.util,
            l.util_frac,
            l.load,
            l.load_frac,
            l.tasks,
            width = header_width,
        );
        info!(
            "  {:<width$}  tot={:7} local={} wake/exp/last/reenq={}/{}/{}/{}",
            "",
            l.total,
            fmt_pct(l.sel_local),
            fmt_pct(l.enq_wakeup),
            fmt_pct(l.enq_expire),
            fmt_pct(l.enq_last),
            fmt_pct(l.enq_reenq),
            width = header_width,
        );
        info!(
            "  {:<width$}  keep/max/busy={}/{}/{} kick={} yield/ign={}/{}",
            "",
            fmt_pct(l.keep),
            fmt_pct(l.keep_fail_max_exec),
            fmt_pct(l.keep_fail_busy),
            fmt_pct(l.kick),
            fmt_pct(l.yielded),
            fmt_num(l.yield_ignore),
            width = header_width,
        );
        info!(
            "  {:<width$}  open_idle={} mig={} affn_viol={}",
            "",
            fmt_pct(l.open_idle),
            fmt_pct(l.migration),
            fmt_pct(l.affn_viol),
            width = header_width,
        );
        info!(
            "  {:<width$}  preempt/first/idle/fail={}/{}/{}/{} min_exec={}/{:7.2}ms",
            "",
            fmt_pct(l.preempt),
            fmt_pct(l.preempt_first),
            fmt_pct(l.preempt_idle),
            fmt_pct(l.preempt_fail),
            fmt_pct(l.min_exec),
            l.min_exec_us as f64 / 1000.0,
            width = header_width,
        );
        info!(
            "  {:<width$}  cpus={:3} [{:3},{:3}]",
            "",
            l.cur_nr_cpus,
            l.min_nr_cpus,
            l.max_nr_cpus,
            //format_bitvec(&layer.cpus),
            width = header_width
        );
        if l.is_excl != 0 {
            info!(
                "  {:<width$}  excl_coll={} excl_preempt={}",
                "",
                fmt_pct(l.excl_collision),
                fmt_pct(l.excl_preempt),
                width = header_width,
            );
        } else if l.excl_collision != 0.0 || l.excl_preempt != 0.0 {
            warn!(
                "{}: exclusive is off but excl_coll={} excl_preempt={}",
                name,
                fmt_pct(l.excl_collision),
                fmt_pct(l.excl_preempt),
            );
        }
    }
}

pub fn monitor(shutdown: Arc<AtomicBool>) -> Result<()> {
    let mut client = ScxStatsClient::new().connect()?;
    while !shutdown.load(Ordering::Relaxed) {
        let sst = client.request::<SysStats>("stat", vec![])?;
        print_sys_stats(&sst);
        std::thread::sleep(Duration::from_secs_f64(sst.intv));
    }
    Ok(())
}
