use clap::ValueEnum;
use zbus::proxy;

/*
 * D-bus interface info
 */

#[proxy(
    interface = "org.scx.Loader",
    default_path = "/org/scx/Loader",
    assume_defaults = true
)]
pub trait ScxLoader {
    /// StartScheduler method
    fn start_scheduler(&self, scx_name: String, sched_mode: u32) -> zbus::Result<()>;

    /// StartSchedulerWithArgs method
    fn start_scheduler_with_args(
        &self,
        scx_name: String,
        scx_args: Vec<String>,
    ) -> zbus::Result<()>;

    /// StopScheduler method
    fn stop_scheduler(&self) -> zbus::Result<()>;

    /// SwitchScheduler method
    fn switch_scheduler(&self, scx_name: String, sched_mode: u32) -> zbus::Result<()>;

    /// SwitchSchedulerWithArgs method
    fn switch_scheduler_with_args(
        &self,
        scx_name: String,
        scx_args: Vec<String>,
    ) -> zbus::Result<()>;

    /// CurrentScheduler property
    #[zbus(property)]
    fn current_scheduler(&self) -> zbus::Result<String>;

    /// SchedulerMode property
    #[zbus(property)]
    fn scheduler_mode(&self) -> zbus::Result<u32>;

    /// SupportedSchedulers property
    #[zbus(property)]
    fn supported_schedulers(&self) -> zbus::Result<Vec<String>>;
}

/*
 * Type Helpers
 */

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum ScxLoaderMode {
    Auto,
    Gaming,
    Powersave,
    Lowlatency,
    Server,
}
impl ScxLoaderMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScxLoaderMode::Auto => "auto",
            ScxLoaderMode::Gaming => "gaming",
            ScxLoaderMode::Powersave => "powersave",
            ScxLoaderMode::Lowlatency => "lowlatency",
            ScxLoaderMode::Server => "server",
        }
    }

    pub fn as_u32(&self) -> u32 {
        match self {
            ScxLoaderMode::Auto => 0,
            ScxLoaderMode::Gaming => 1,
            ScxLoaderMode::Powersave => 2,
            ScxLoaderMode::Lowlatency => 3,
            ScxLoaderMode::Server => 4,
        }
    }

    pub fn from_u32(u: u32) -> Option<Self> {
        match u {
            0 => Some(ScxLoaderMode::Auto),
            1 => Some(ScxLoaderMode::Gaming),
            2 => Some(ScxLoaderMode::Powersave),
            3 => Some(ScxLoaderMode::Lowlatency),
            4 => Some(ScxLoaderMode::Server),
            _ => None,
        }
    }
}
