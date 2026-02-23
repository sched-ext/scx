// PANDEMONIUM STRUCTURED LOGGING
// TIMESTAMPED [HH:MM:SS] [LEVEL] FORMAT
// MIRRORS pandemonium.py AND tests/scale.rs PATTERN

pub fn _timestamp() -> String {
    unsafe {
        let mut t: libc::time_t = 0;
        libc::time(&mut t);
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        format!("[{:02}:{:02}:{:02}]", tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
}

macro_rules! log_info {
    ($($arg:tt)*) => {
        println!("{} [INFO]   {}", crate::log::_timestamp(), format!($($arg)*))
    };
}

macro_rules! log_warn {
    ($($arg:tt)*) => {
        println!("{} [WARN]   {}", crate::log::_timestamp(), format!($($arg)*))
    };
}

macro_rules! log_error {
    ($($arg:tt)*) => {
        println!("{} [ERROR]  {}", crate::log::_timestamp(), format!($($arg)*))
    };
}
