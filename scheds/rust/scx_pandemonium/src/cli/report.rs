use anyhow::Result;

use super::LOG_DIR;

fn chrono_stamp() -> String {
    let output = std::process::Command::new("date")
        .arg("+%Y%m%d-%H%M%S")
        .output()
        .ok();
    match output {
        Some(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        }
        _ => "unknown".to_string(),
    }
}

pub fn save_report(content: &str, prefix: &str) -> Result<String> {
    std::fs::create_dir_all(LOG_DIR)?;
    let stamp = chrono_stamp();
    let path = format!("{}/{}-{}.log", LOG_DIR, prefix, stamp);
    std::fs::write(&path, content)?;
    Ok(path)
}

pub fn mean_stdev(values: &[f64]) -> (f64, f64) {
    let n = values.len();
    if n == 0 {
        return (0.0, 0.0);
    }
    let m: f64 = values.iter().sum::<f64>() / n as f64;
    if n == 1 {
        return (m, 0.0);
    }
    let variance: f64 = values.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (n - 1) as f64;
    (m, variance.sqrt())
}

pub fn percentile(sorted_vals: &[f64], p: f64) -> f64 {
    if sorted_vals.is_empty() {
        return 0.0;
    }
    let idx = (sorted_vals.len() as f64 * p / 100.0) as usize;
    let idx = idx.min(sorted_vals.len() - 1);
    sorted_vals[idx]
}

pub fn format_delta(delta_pct: f64, label: &str) -> String {
    if delta_pct < 0.0 {
        format!(
            "{} DELTA: {:+.1}% (PANDEMONIUM IS {:.1}% FASTER)",
            label,
            delta_pct,
            delta_pct.abs()
        )
    } else if delta_pct > 0.0 {
        format!(
            "{} DELTA: {:+.1}% (PANDEMONIUM IS {:.1}% SLOWER)",
            label, delta_pct, delta_pct
        )
    } else {
        format!("{} DELTA: 0.0% (NO DIFFERENCE)", label)
    }
}

pub fn format_latency_delta(delta_us: f64, label: &str) -> String {
    if delta_us < 0.0 {
        format!(
            "{} LATENCY DELTA: {:+.0}us (PANDEMONIUM IS {:.0}us BETTER)",
            label,
            delta_us,
            delta_us.abs()
        )
    } else if delta_us > 0.0 {
        format!(
            "{} LATENCY DELTA: {:+.0}us (PANDEMONIUM IS {:.0}us WORSE)",
            label, delta_us, delta_us
        )
    } else {
        format!("{} LATENCY DELTA: 0us (SAME)", label)
    }
}
