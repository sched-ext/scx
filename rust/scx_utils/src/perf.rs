#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use libc::pid_t;
use std::os::raw::{c_int, c_ulong};

/// The `perf_event_open` system call.
///
/// See the [`perf_event_open(2) man page`][man] for details.
///
/// On error, this returns -1, and the C `errno` value (accessible via
/// `std::io::Error::last_os_error`) is set to indicate the error.
///
/// Note: The `attrs` argument needs to be a `*mut` because if the `size` field
/// is too small or too large, the kernel writes the size it was expecing back
/// into that field. It might do other things as well.
///
/// # Safety
///
/// The `attrs` argument must point to a properly initialized
/// `perf_event_attr` struct. The measurements and other behaviors its
/// contents request must be safe.
///
/// [man]: https://www.mankier.com/2/perf_event_open
pub unsafe fn perf_event_open(
    attrs: *mut bindings::perf_event_attr,
    pid: pid_t,
    cpu: c_int,
    group_fd: c_int,
    flags: c_ulong,
) -> c_int {
    unsafe {
        libc::syscall(
            bindings::__NR_perf_event_open as libc::c_long,
            attrs as *const bindings::perf_event_attr,
            pid,
            cpu,
            group_fd,
            flags,
        ) as c_int
    }
}

pub mod bindings {
    include!(concat!(env!("OUT_DIR"), "/perf_bindings.rs"));
}

pub mod ioctls {
    use crate::perf;
    use std::os::raw::{c_int, c_uint};

    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn enable(fd: c_int, arg: c_uint) -> c_int {
        unsafe { libc::ioctl(fd, perf::bindings::ENABLE as libc::Ioctl, arg) }
    }

    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn reset(fd: c_int, arg: c_uint) -> c_int {
        unsafe { libc::ioctl(fd, perf::bindings::RESET as libc::Ioctl, arg) }
    }
}
