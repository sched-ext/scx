use std::fmt;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

use zbus::blocking::Connection;
use zbus::proxy;
use zbus::Result;

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
    Balanced { power: bool },
    Performance,
    Unknown,
}

impl fmt::Display for PowerProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PowerProfile::Powersave => "powersave",
            PowerProfile::Balanced { power: true } => "balanced_power",
            PowerProfile::Balanced { power: false } => "balanced_performance",
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
            "power" | "powersave" => PowerProfile::Powersave,
            "balance_power" => PowerProfile::Balanced { power: true },
            "balance_performance" => PowerProfile::Balanced { power: false },
            "performance" => PowerProfile::Performance,
            _ => PowerProfile::Unknown,
        })
        .unwrap_or(PowerProfile::Unknown)
}

pub fn fetch_power_profile(no_ppd: bool) -> PowerProfile {
    fn parse_profile(profile: &str) -> PowerProfile {
        match profile {
            "power-saver" => PowerProfile::Powersave,
            "balanced" => PowerProfile::Balanced { power: false },
            "performance" => PowerProfile::Performance,
            _ => PowerProfile::Unknown,
        }
    }

    if no_ppd {
        return read_energy_profile();
    }
    let proxy = POWER_PROFILES_PROXY.get();
    if let Some(proxy) = proxy {
        proxy.active_profile().map_or_else(
            |e| {
                log::debug!("failed to fetch the active power profile from ppd: {e}");
                read_energy_profile()
            },
            |profile| parse_profile(&profile),
        )
    } else {
        let retries = RETRIES.fetch_add(1, Ordering::Relaxed);
        if retries < MAX_RETRIES {
            let proxy = Connection::system().map(Box::new).map(Box::leak).map(|bus|
                    // This cannot fail. Proxy::new() does not check the existence of interface
                    PowerProfilesProxyBlocking::new(bus).unwrap());
            match proxy {
                Ok(proxy) => match proxy.active_profile() {
                    Ok(profile) => {
                        let _ = POWER_PROFILES_PROXY.set(proxy);
                        parse_profile(&profile)
                    }
                    Err(e) => {
                        log::debug!("failed to communicate with ppd (retry {retries}): {e}");
                        read_energy_profile()
                    }
                },
                Err(e) => {
                    log::debug!("failed to communicate with dbus (retry {retries}): {e}");
                    read_energy_profile()
                }
            }
        } else {
            read_energy_profile()
        }
    }
}
