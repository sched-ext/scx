// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use scx_utils::mangoapp::{mangoapp_msg_v1, MANGOAPP_PROJ_ID};

use anyhow::bail;
use anyhow::Result;
use libc::{msgget, msgrcv, IPC_NOWAIT};

use std::mem;
use std::path::Path;
use std::thread;
use std::time::Duration;
use std::{ffi::CString, io};

fn main() -> Result<()> {
    // NOTE: the mangoapp file has to be present when gamescope launches in order to read from the
    // message queue. For example when launching Counter Strike 2 the mangoapp file needs to be in
    // $HOME/.local/share/Steam/steamapps/common/Counter-String Global Offensive/mangoapp and the
    // program needs to run in the same directory as well.
    let file_path = Path::new("mangoapp");
    if !file_path.exists() {
        bail!("mangoapp file does not exists");
    }

    // Create the key for msgget reads using the mangoapp file
    let path = CString::new("mangoapp").unwrap();
    let key = unsafe { libc::ftok(path.as_ptr(), MANGOAPP_PROJ_ID) };
    if key == -1 {
        bail!("failed to ftok: {}", io::Error::last_os_error());
    }

    // Get the key from the queue
    let msgid = unsafe { msgget(key.try_into().unwrap(), 0) };
    if msgid == -1 {
        bail!("msgget failed: {}", std::io::Error::last_os_error());
    }

    let mut raw_msg: mangoapp_msg_v1 = unsafe { mem::zeroed() };

    loop {
        let msg_size = unsafe {
            msgrcv(
                msgid,
                &mut raw_msg as *mut _ as *mut libc::c_void,
                mem::size_of::<mangoapp_msg_v1>() - mem::size_of::<i64>(),
                0,
                IPC_NOWAIT, // XXX: this should probably use MSG_COPY as it pulls messages off the
                            // queue and may mess with mangohud or other mangoapp uses.
            )
        };

        if msg_size as isize != -1 {
            let frametime = raw_msg.visible_frametime_ns;
            let upscale = raw_msg.fsr_upscale;
            let sharpness = raw_msg.fsr_sharpness;
            let app_frametime_ns = raw_msg.app_frametime_ns;
            let pid = raw_msg.pid;
            let latency_ns = raw_msg.latency_ns;
            let output_width = raw_msg.output_width;
            let output_height = raw_msg.output_height;
            let wants_hdr = raw_msg.wants_hdr();
            let steam_focused = raw_msg.steam_focused();

            println!("Received MangoApp data:");
            println!("  Visible Frametime: {}", frametime);
            println!("  FSR Upscale: {}", upscale);
            println!("  FSR Sharpness: {}", sharpness);
            println!("  App Frametime: {}", app_frametime_ns);
            println!("  Latency: {}", latency_ns);
            println!("  PID: {}", pid);
            println!("  Output Width: {}", output_width);
            println!("  Output Height: {}", output_height);
            println!("  App Wants HDR: {}", wants_hdr);
            println!("  Steam Focused: {}", steam_focused);
            println!(
                "  Engine Name: {}",
                String::from_utf8_lossy(unsafe {
                    &*(raw_msg.engine_name.as_ptr() as *const [u8; 40])
                })
            );
        } else {
            bail!(
                "mangoapp: msgrcv returned -1 with error {}",
                io::Error::last_os_error()
            );
        }
        thread::sleep(Duration::from_secs(1));
    }
}
