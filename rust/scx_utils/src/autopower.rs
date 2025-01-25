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

fn read_energy_profile() -> String {
    let energy_pref_path = "/sys/devices/system/cpu/cpufreq/policy0/energy_performance_preference";
    let scaling_governor_path = "/sys/devices/system/cpu/cpufreq/policy0/scaling_governor";

    fs::read_to_string(energy_pref_path)
        .ok()
        .or_else(|| fs::read_to_string(scaling_governor_path).ok())
        .and_then(|s| {
            Some(match s.trim_end() {
                "power" | "balance_power" | "powersave" => "power-saver",
                "balance_performance" => "balanced",
                "performance" => "performance",
                _ => return None,
            })
        })
        .unwrap_or_default()
        .to_string()
}

pub fn fetch_power_profile(no_ppd: bool) -> String {
    if no_ppd {
        return read_energy_profile();
    }
    let proxy = POWER_PROFILES_PROXY.get();
    if let Some(proxy) = proxy {
        proxy.active_profile().unwrap_or_else(|e| {
            warn!("failed to fetch the active power profile from ppd: {e}");
            read_energy_profile()
        })
    } else {
        let retries = RETRIES.fetch_add(1, Ordering::Relaxed);
        if retries < MAX_RETRIES {
            let proxy = (|| {
                let system_bus = Connection::system().ok()?;
                let system_bus = Box::leak(Box::new(system_bus));
                PowerProfilesProxyBlocking::new(system_bus).ok()
            })();
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
