use std::fmt;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

use zbus::blocking::Connection;
use zbus::proxy;
use zbus::Result;

use crate::warn;

#[proxy(
    interface = "net.hadess.PowerProfiles",
    default_service = "net.hadess.PowerProfiles",
    default_path = "/net/hadess/PowerProfiles"
)]
trait PowerProfiles {
    #[zbus(property)]
    fn active_profile(&self) -> Result<String>;
}

static POWER_PROFILES_PROXY: OnceLock<PowerProfilesProxyBlocking<'static>> = OnceLock::new();
static RETRIES: AtomicUsize = AtomicUsize::new(0);
const MAX_RETRIES: usize = 10;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PowerProfile {
    Powersave,
    Balanced,
    Performance,
    Unknown,
}

impl fmt::Display for PowerProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PowerProfile::Powersave => "powersave",
            PowerProfile::Balanced => "balanced",
            PowerProfile::Performance => "performance",
            PowerProfile::Unknown => "unknown",
        }
        .fmt(f)
    }
}

fn read_energy_profile() -> PowerProfile {
    let energy_pref_path = "/sys/devices/system/cpu/cpufreq/policy0/energy_performance_preference";
    let scaling_governor_path = "/sys/devices/system/cpu/cpufreq/policy0/scaling_governor";

    fs::read_to_string(energy_pref_path)
        .ok()
        .or_else(|| fs::read_to_string(scaling_governor_path).ok())
        .map(|s| match s.trim_end() {
            "power" | "balance_power" | "powersave" => PowerProfile::Powersave,
            "balance_performance" => PowerProfile::Balanced,
            "performance" => PowerProfile::Performance,
            _ => PowerProfile::Unknown,
        })
        .unwrap_or(PowerProfile::Unknown)
}

pub fn fetch_power_profile(no_ppd: bool) -> PowerProfile {
    if no_ppd {
        return read_energy_profile();
    }
    let proxy = POWER_PROFILES_PROXY.get();
    if let Some(proxy) = proxy {
        proxy.active_profile().map_or_else(
            |e| {
                warn!("failed to fetch the active power profile from ppd: {e}");
                read_energy_profile()
            },
            |profile| match profile.as_str() {
                "power-saver" => PowerProfile::Powersave,
                "balanced" => PowerProfile::Balanced,
                "performance" => PowerProfile::Performance,
                _ => PowerProfile::Unknown,
            },
        )
    } else {
        let retries = RETRIES.fetch_add(1, Ordering::Relaxed);
        if retries < MAX_RETRIES {
            let proxy = Connection::system()
                .ok()
                .map(Box::new)
                .map(Box::leak)
                .as_deref()
                .map(PowerProfilesProxyBlocking::new)
                .and_then(Result::ok);
            if let Some(proxy) = proxy {
                let _ = POWER_PROFILES_PROXY.set(proxy);
                fetch_power_profile(false)
            } else {
                warn!("failed to communicate with ppd: retry {retries}");
                read_energy_profile()
            }
        } else {
            read_energy_profile()
        }
    }
}
