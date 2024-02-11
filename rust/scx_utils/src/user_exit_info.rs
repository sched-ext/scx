// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use crate::bindings;
use anyhow::bail;
use anyhow::Result;
use std::ffi::CStr;
use std::os::raw::c_char;

pub enum ScxExitKind {
    None = bindings::scx_exit_kind_SCX_EXIT_NONE as isize,
    Done = bindings::scx_exit_kind_SCX_EXIT_DONE as isize,
    Unreg = bindings::scx_exit_kind_SCX_EXIT_UNREG as isize,
    SysRq = bindings::scx_exit_kind_SCX_EXIT_SYSRQ as isize,
    Error = bindings::scx_exit_kind_SCX_EXIT_ERROR as isize,
    ErrorBPF = bindings::scx_exit_kind_SCX_EXIT_ERROR_BPF as isize,
    ErrorStall = bindings::scx_exit_kind_SCX_EXIT_ERROR_STALL as isize,
}

/// Takes a reference to C struct user_exit_info and reads it into
/// UserExitInfo. See UserExitInfo.
#[macro_export]
macro_rules! uei_read {
    ($bpf_uei:expr) => {{
        {
            let bpf_uei = $bpf_uei;
            scx_utils::UserExitInfo::new(
                &bpf_uei.kind as *const _,
                bpf_uei.reason.as_ptr() as *const _,
                bpf_uei.msg.as_ptr() as *const _,
                bpf_uei.dump.as_ptr() as *const _,
            )
        }
    }};
}

/// Takes a reference to C struct user_exit_info and test whether the BPF
/// scheduler has exited. See UserExitInfo.
#[macro_export]
macro_rules! uei_exited {
    ($bpf_uei:expr) => {{
        (unsafe { std::ptr::read_volatile(&$bpf_uei.kind as *const _) } != 0)
    }};
}

/// Takes a reference to C struct user_exit_info, reads it and invokes
/// UserExitInfo::report() on it. See UserExitInfo.
#[macro_export]
macro_rules! uei_report {
    ($bpf_uei:expr) => {{
        scx_utils::uei_read!($bpf_uei).report()
    }};
}

/// Rust counterpart of C struct user_exit_info.
#[derive(Debug, Default)]
pub struct UserExitInfo {
    /// The C enum scx_exit_kind value. Test against ScxExitKind. None-zero
    /// value indicates that the BPF scheduler has exited.
    kind: i32,
    reason: Option<String>,
    msg: Option<String>,
    dump: Option<String>,
}

impl UserExitInfo {
    /// Create UserExitInfo from C struct user_exit_info. Each scheduler
    /// implementation creates its own Rust binding for the C struct
    /// user_exit_info, so we can't take the type directly. Instead, this
    /// method takes each member field. Use the macro uei_read!() on the C
    /// type which then calls this method with the individual fields.
    pub fn new(
        kind_ptr: *const i32,
        reason_ptr: *const c_char,
        msg_ptr: *const c_char,
        dump_ptr: *const c_char,
    ) -> Self {
        let kind = unsafe { std::ptr::read_volatile(kind_ptr) };

        let (reason, msg, dump) = (
            Some(
                unsafe { CStr::from_ptr(reason_ptr) }
                    .to_str()
                    .expect("Failed to convert reason to string")
                    .to_string(),
            )
            .filter(|s| !s.is_empty()),
            Some(
                unsafe { CStr::from_ptr(msg_ptr) }
                    .to_str()
                    .expect("Failed to convert msg to string")
                    .to_string(),
            )
            .filter(|s| !s.is_empty()),
            Some(
                unsafe { CStr::from_ptr(dump_ptr) }
                    .to_str()
                    .expect("Failed to convert msg to string")
                    .to_string(),
            )
            .filter(|s| !s.is_empty()),
        );

        Self {
            kind,
            reason,
            msg,
            dump,
        }
    }

    /// Print out the exit message to stderr if the exit was normal. After
    /// an error exit, it throws an error containing the exit message
    /// instead. If debug dump exists, it's always printed to stderr.
    pub fn report(&self) -> Result<()> {
        if self.kind == 0 {
            return Ok(());
        }

	if let Some(dump) = &self.dump {
	    eprintln!("\nDEBUG DUMP");
	    eprintln!("================================================================================\n");
	    eprintln!("{}", dump);
	    eprintln!("================================================================================\n");
	}

        let why = match (&self.reason, &self.msg) {
            (Some(reason), None) => format!("EXIT: {}", reason),
            (Some(reason), Some(msg)) => format!("EXIT: {} ({})", reason, msg),
            _ => "<UNKNOWN>".into(),
        };

        if self.kind <= ScxExitKind::Unreg as i32 {
            eprintln!("{}", why);
            Ok(())
        } else {
            bail!("{}", why)
        }
    }
}
