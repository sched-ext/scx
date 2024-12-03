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

static POWER_PROFILES_PROXY: OnceLock<Option<PowerProfilesProxyBlocking<'static>>> =
    OnceLock::new();

pub fn fetch_power_profile() -> String {
    POWER_PROFILES_PROXY
        .get_or_init(|| {
            let system_bus = Connection::system().ok()?;
            let system_bus = Box::leak(Box::new(system_bus));
            PowerProfilesProxyBlocking::new(system_bus).ok()
        })
        .as_ref()
        .map(|power_profiles_proxy| power_profiles_proxy.active_profile().ok())
        .flatten()
        .unwrap_or_default()
}
