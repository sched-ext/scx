use std::sync::atomic::{AtomicBool, Ordering};

/// Create a pipe for parent-death detection.
/// Returns (read_fd, write_fd). Neither end has CLOEXEC set.
/// Parent holds write_fd open. Child monitors read_fd for POLLHUP.
pub fn create_death_pipe() -> Result<(i32, i32), std::io::Error> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

pub fn close_fd(fd: i32) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

/// Monitor a death pipe FD in a background thread.
/// When the write end closes (parent dies), POLLHUP fires and `running`
/// is set to false, triggering the probe's graceful shutdown.
pub fn spawn_death_watcher(death_fd: i32, running: &'static AtomicBool) {
    std::thread::Builder::new()
        .name("death-watcher".into())
        .spawn(move || {
            let mut pfd = libc::pollfd {
                fd: death_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            while running.load(Ordering::Relaxed) {
                let ret = unsafe { libc::poll(&mut pfd, 1, 100) };
                if ret > 0 && (pfd.revents & (libc::POLLHUP | libc::POLLERR)) != 0 {
                    running.store(false, Ordering::Relaxed);
                    break;
                }
                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() != std::io::ErrorKind::Interrupted {
                        running.store(false, Ordering::Relaxed);
                        break;
                    }
                }
            }
            unsafe {
                libc::close(death_fd);
            }
        })
        .ok();
}
